rule TTP_XOR_WriteProcessMemory_cbcd {
  strings:
    $key_cbcd = { 9c bf [2] ae 9d [2] a8 a8 [2] 86 a8 [2] b9 b4 }

  condition:
    any of them
}