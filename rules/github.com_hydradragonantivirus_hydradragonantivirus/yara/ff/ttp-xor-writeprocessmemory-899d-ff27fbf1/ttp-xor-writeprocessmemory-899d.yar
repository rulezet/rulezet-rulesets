rule TTP_XOR_WriteProcessMemory_899d {
  strings:
    $key_899d = { de ef [2] ec cd [2] ea f8 [2] c4 f8 [2] fb e4 }

  condition:
    any of them
}