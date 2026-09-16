rule TTP_XOR_WriteProcessMemory_361f {
  strings:
    $key_361f = { 61 6d [2] 53 4f [2] 55 7a [2] 7b 7a [2] 44 66 }

  condition:
    any of them
}