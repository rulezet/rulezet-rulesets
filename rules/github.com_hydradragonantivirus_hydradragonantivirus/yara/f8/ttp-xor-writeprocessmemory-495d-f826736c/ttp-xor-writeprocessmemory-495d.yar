rule TTP_XOR_WriteProcessMemory_495d {
  strings:
    $key_495d = { 1e 2f [2] 2c 0d [2] 2a 38 [2] 04 38 [2] 3b 24 }

  condition:
    any of them
}