rule TTP_XOR_WriteProcessMemory_f7cf {
  strings:
    $key_f7cf = { a0 bd [2] 92 9f [2] 94 aa [2] ba aa [2] 85 b6 }

  condition:
    any of them
}