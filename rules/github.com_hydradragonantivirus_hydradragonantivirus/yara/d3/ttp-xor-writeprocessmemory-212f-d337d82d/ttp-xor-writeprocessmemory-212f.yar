rule TTP_XOR_WriteProcessMemory_212f {
  strings:
    $key_212f = { 76 5d [2] 44 7f [2] 42 4a [2] 6c 4a [2] 53 56 }

  condition:
    any of them
}