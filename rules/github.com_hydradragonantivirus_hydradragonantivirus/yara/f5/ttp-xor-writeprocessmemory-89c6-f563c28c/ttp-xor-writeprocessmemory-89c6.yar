rule TTP_XOR_WriteProcessMemory_89c6 {
  strings:
    $key_89c6 = { de b4 [2] ec 96 [2] ea a3 [2] c4 a3 [2] fb bf }

  condition:
    any of them
}