rule TTP_XOR_WriteProcessMemory_8977 {
  strings:
    $key_8977 = { de 05 [2] ec 27 [2] ea 12 [2] c4 12 [2] fb 0e }

  condition:
    any of them
}