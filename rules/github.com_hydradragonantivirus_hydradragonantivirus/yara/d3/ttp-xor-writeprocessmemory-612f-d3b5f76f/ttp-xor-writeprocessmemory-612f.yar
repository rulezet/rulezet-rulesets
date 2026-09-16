rule TTP_XOR_WriteProcessMemory_612f {
  strings:
    $key_612f = { 36 5d [2] 04 7f [2] 02 4a [2] 2c 4a [2] 13 56 }

  condition:
    any of them
}