rule TTP_XOR_WriteProcessMemory_d3fa {
  strings:
    $key_d3fa = { 84 88 [2] b6 aa [2] b0 9f [2] 9e 9f [2] a1 83 }

  condition:
    any of them
}