rule TTP_XOR_WriteProcessMemory_c5da {
  strings:
    $key_c5da = { 92 a8 [2] a0 8a [2] a6 bf [2] 88 bf [2] b7 a3 }

  condition:
    any of them
}