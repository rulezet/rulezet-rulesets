rule ct_size_10mb_100mb {
  condition:
    filesize > 10MB and filesize < 100MB
}