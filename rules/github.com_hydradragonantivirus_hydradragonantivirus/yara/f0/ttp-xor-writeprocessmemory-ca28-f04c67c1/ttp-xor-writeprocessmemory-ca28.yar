rule TTP_XOR_WriteProcessMemory_ca28 {
  strings:
    $key_ca28 = { 9d 5a [2] af 78 [2] a9 4d [2] 87 4d [2] b8 51 }

  condition:
    any of them
}