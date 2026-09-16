rule TTP_XOR_WriteProcessMemory_6dcf {
  strings:
    $key_6dcf = { 3a bd [2] 08 9f [2] 0e aa [2] 20 aa [2] 1f b6 }

  condition:
    any of them
}