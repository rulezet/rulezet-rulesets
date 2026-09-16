rule PEiD_01908_RAR_Configuration_file_ {
  meta:
    description = "[RAR Configuration file]"
    ep_only     = "false"

  strings:
    $a = "RAR CONFIG"

  condition:
    $a
}