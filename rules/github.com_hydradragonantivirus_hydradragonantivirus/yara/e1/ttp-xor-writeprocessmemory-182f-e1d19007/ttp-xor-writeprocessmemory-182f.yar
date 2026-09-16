rule TTP_XOR_WriteProcessMemory_182f {
  strings:
    $key_182f = { 4f 5d [2] 7d 7f [2] 7b 4a [2] 55 4a [2] 6a 56 }

  condition:
    any of them
}