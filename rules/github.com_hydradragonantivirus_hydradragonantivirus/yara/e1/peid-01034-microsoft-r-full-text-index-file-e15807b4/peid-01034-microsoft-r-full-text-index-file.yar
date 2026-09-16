rule PEiD_01034_Microsoft__R__Full_text_index_file_ {
  meta:
    description = "[Microsoft (R) Full-text index file]"
    ep_only     = "false"

  strings:
    $a = "ll-text index"

  condition:
    $a
}