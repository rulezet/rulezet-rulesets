rule TTP_XOR_WriteProcessMemory_61da {
  strings:
    $key_61da = { 36 a8 [2] 04 8a [2] 02 bf [2] 2c bf [2] 13 a3 }

  condition:
    any of them
}