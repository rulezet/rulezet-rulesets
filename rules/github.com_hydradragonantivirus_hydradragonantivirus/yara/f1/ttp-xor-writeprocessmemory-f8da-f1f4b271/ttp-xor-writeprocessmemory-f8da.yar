rule TTP_XOR_WriteProcessMemory_f8da {
  strings:
    $key_f8da = { af a8 [2] 9d 8a [2] 9b bf [2] b5 bf [2] 8a a3 }

  condition:
    any of them
}