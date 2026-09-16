rule TTP_XOR_WriteProcessMemory_ca49 {
  strings:
    $key_ca49 = { 9d 3b [2] af 19 [2] a9 2c [2] 87 2c [2] b8 30 }

  condition:
    any of them
}