rule TTP_XOR_WriteProcessMemory_8904 {
  strings:
    $key_8904 = { de 76 [2] ec 54 [2] ea 61 [2] c4 61 [2] fb 7d }

  condition:
    any of them
}