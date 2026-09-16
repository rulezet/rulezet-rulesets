rule TTP_XOR_WriteProcessMemory_692f {
  strings:
    $key_692f = { 3e 5d [2] 0c 7f [2] 0a 4a [2] 24 4a [2] 1b 56 }

  condition:
    any of them
}