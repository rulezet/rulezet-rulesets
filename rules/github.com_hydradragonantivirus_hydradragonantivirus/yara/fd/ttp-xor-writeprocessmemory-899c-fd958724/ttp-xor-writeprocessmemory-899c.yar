rule TTP_XOR_WriteProcessMemory_899c {
  strings:
    $key_899c = { de ee [2] ec cc [2] ea f9 [2] c4 f9 [2] fb e5 }

  condition:
    any of them
}