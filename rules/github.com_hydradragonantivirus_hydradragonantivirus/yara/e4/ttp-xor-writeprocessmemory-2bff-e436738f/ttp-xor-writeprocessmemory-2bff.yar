rule TTP_XOR_WriteProcessMemory_2bff {
  strings:
    $key_2bff = { 7c 8d [2] 4e af [2] 48 9a [2] 66 9a [2] 59 86 }

  condition:
    any of them
}