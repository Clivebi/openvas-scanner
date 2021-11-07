#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_signature.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <ctype.h> /* for isalpha */
#include <gcrypt.h>
#include <glib.h>
#include <gvm/base/logging.h>
#include <gvm/base/prefs.h>
#include <libgen.h>
#include <pcap.h> /* for islocalhost */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>   /* for strlen */
#include <sys/stat.h> /* for stat */
#include <unistd.h>   /* for getpid */

#ifdef USE_VFS

#include "vfsreader.h"

static vfs_handle_p g_vfs = NULL;
static int g_vfs_owner = 0;
static void
nasl_init_vfs ()
{
  char *content = NULL;
  int dic_size = 0;
  const char *plugins_folder = prefs_get ("plugins_folder");
  char *vfs_path = g_build_filename (plugins_folder, "vfs.img", NULL);
  char *dic_path = g_build_filename (plugins_folder, "vfs.dic", NULL);
  content = vfs_read_file_content (dic_path, &dic_size);
  if (content == NULL)
    {
      g_error ("load dic error\n");
      abort ();
    }
  g_vfs = vfs_open (vfs_path, content, dic_size);
  g_vfs_owner = getpid ();
  g_free (content);
  g_free (vfs_path);
  g_free (dic_path);
}

void
nasl_close_vfs ()
{
  if (getpid () == g_vfs_owner)
    {
      if (g_vfs != NULL)
        {
          vfs_close (g_vfs);
          g_vfs = NULL;
        }
    }
}

char *
nasl_read_script_from_vfs (const char *name, int *content_size)
{
  char *content = NULL;
  vfs_dir_entry_p entry = NULL;
  const char *plugins_folder = prefs_get ("plugins_folder");
  if (g_vfs == NULL || g_vfs_owner != getpid ())
    {
      nasl_init_vfs ();
    }
  if (g_str_has_prefix (name, plugins_folder))
    {
      name += strlen (plugins_folder);
    }
  entry = vfs_lookup (g_vfs, name);
  if (entry != NULL)
    {
      *content_size = vfs_file_size (entry);
      content = vfs_get_file_all_content (g_vfs, entry, NULL);
    }
  return content;
}

GSList *
collect_nvts_from_vfs (GSList *files)
{
  int count = 0, path_size = 0;
  char full_name[512] = {0};
  const vfs_dir_entry_p *all_list = NULL;
  vfs_dir_entry_p entry = NULL;
  if (g_vfs == NULL || g_vfs_owner != getpid ())
    {
      nasl_init_vfs ();
    }
  all_list = vfs_get_all_files (g_vfs, &count);
  for (int i = 0; i < count; i++)
    {
      entry = all_list[i];
      path_size = sizeof (full_name);
      memset (full_name, 0, sizeof (full_name));
      vfs_get_file_full_path (g_vfs, entry, full_name, &path_size);
      if (g_str_has_suffix (full_name, ".nasl"))
        {
          if (full_name[0] == '/')
            {
              files = g_slist_prepend (files, g_strdup (full_name + 1));
            }
          else
            {
              files = g_slist_prepend (files, g_strdup (full_name));
            }
        }
    }
  return files;
}

#endif
