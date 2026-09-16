rule TTP_XOR_WriteProcessMemory_6ad8 {
  strings:
    $key_6ad8 = { 3d aa [2] 0f 88 [2] 09 bd [2] 27 bd [2] 18 a1 }

  condition:
    any of them
}