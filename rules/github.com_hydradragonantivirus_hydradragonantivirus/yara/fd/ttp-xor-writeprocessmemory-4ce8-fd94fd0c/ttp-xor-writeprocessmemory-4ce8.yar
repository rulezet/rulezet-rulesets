rule TTP_XOR_WriteProcessMemory_4ce8 {
  strings:
    $key_4ce8 = { 1b 9a [2] 29 b8 [2] 2f 8d [2] 01 8d [2] 3e 91 }

  condition:
    any of them
}