rule TTP_XOR_WriteProcessMemory_2ce8 {
  strings:
    $key_2ce8 = { 7b 9a [2] 49 b8 [2] 4f 8d [2] 61 8d [2] 5e 91 }

  condition:
    any of them
}