rule TTP_XOR_WriteProcessMemory_267f {
  strings:
    $key_267f = { 71 0d [2] 43 2f [2] 45 1a [2] 6b 1a [2] 54 06 }

  condition:
    any of them
}