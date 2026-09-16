rule TTP_XOR_WriteProcessMemory_d3cf {
  strings:
    $key_d3cf = { 84 bd [2] b6 9f [2] b0 aa [2] 9e aa [2] a1 b6 }

  condition:
    any of them
}