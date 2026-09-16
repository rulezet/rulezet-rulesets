rule TTP_XOR_WriteProcessMemory_ca73 {
  strings:
    $key_ca73 = { 9d 01 [2] af 23 [2] a9 16 [2] 87 16 [2] b8 0a }

  condition:
    any of them
}