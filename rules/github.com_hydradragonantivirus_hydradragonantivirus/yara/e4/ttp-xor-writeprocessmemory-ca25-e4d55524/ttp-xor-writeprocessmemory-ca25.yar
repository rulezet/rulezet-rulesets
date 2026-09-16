rule TTP_XOR_WriteProcessMemory_ca25 {
  strings:
    $key_ca25 = { 9d 57 [2] af 75 [2] a9 40 [2] 87 40 [2] b8 5c }

  condition:
    any of them
}