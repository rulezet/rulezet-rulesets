rule ct_size_10kb_100kb {
  condition:
    filesize > 10KB and filesize < 100KB
}