rule TTP_XOR_WriteProcessMemory_197d {
  strings:
    $key_197d = { 4e 0f [2] 7c 2d [2] 7a 18 [2] 54 18 [2] 6b 04 }

  condition:
    any of them
}