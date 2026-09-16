rule TTP_XOR_WriteProcessMemory_362f {
  strings:
    $key_362f = { 61 5d [2] 53 7f [2] 55 4a [2] 7b 4a [2] 44 56 }

  condition:
    any of them
}