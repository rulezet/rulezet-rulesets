rule TTP_XOR_WriteProcessMemory_563f {
  strings:
    $key_563f = { 01 4d [2] 33 6f [2] 35 5a [2] 1b 5a [2] 24 46 }

  condition:
    any of them
}