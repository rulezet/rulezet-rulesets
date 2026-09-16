rule TTP_XOR_WriteProcessMemory_c6ef {
  strings:
    $key_c6ef = { 91 9d [2] a3 bf [2] a5 8a [2] 8b 8a [2] b4 96 }

  condition:
    any of them
}