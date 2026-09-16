rule TTP_XOR_WriteProcessMemory_c4cf {
  strings:
    $key_c4cf = { 93 bd [2] a1 9f [2] a7 aa [2] 89 aa [2] b6 b6 }

  condition:
    any of them
}