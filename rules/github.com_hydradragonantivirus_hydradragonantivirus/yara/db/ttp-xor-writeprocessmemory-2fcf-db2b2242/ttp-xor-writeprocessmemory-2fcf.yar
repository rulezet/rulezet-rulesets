rule TTP_XOR_WriteProcessMemory_2fcf {
  strings:
    $key_2fcf = { 78 bd [2] 4a 9f [2] 4c aa [2] 62 aa [2] 5d b6 }

  condition:
    any of them
}