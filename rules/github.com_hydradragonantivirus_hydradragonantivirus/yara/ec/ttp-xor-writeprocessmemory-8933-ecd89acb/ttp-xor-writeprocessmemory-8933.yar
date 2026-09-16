rule TTP_XOR_WriteProcessMemory_8933 {
  strings:
    $key_8933 = { de 41 [2] ec 63 [2] ea 56 [2] c4 56 [2] fb 4a }

  condition:
    any of them
}