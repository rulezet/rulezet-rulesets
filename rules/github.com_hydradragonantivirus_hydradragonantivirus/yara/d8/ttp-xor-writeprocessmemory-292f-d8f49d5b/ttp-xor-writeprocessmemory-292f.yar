rule TTP_XOR_WriteProcessMemory_292f {
  strings:
    $key_292f = { 7e 5d [2] 4c 7f [2] 4a 4a [2] 64 4a [2] 5b 56 }

  condition:
    any of them
}