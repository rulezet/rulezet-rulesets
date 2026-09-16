rule TTP_XOR_WriteProcessMemory_2d3f {
  strings:
    $key_2d3f = { 7a 4d [2] 48 6f [2] 4e 5a [2] 60 5a [2] 5f 46 }

  condition:
    any of them
}