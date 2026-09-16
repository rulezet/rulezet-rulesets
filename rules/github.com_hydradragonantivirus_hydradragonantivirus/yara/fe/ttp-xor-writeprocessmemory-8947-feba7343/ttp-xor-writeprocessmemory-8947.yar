rule TTP_XOR_WriteProcessMemory_8947 {
  strings:
    $key_8947 = { de 35 [2] ec 17 [2] ea 22 [2] c4 22 [2] fb 3e }

  condition:
    any of them
}