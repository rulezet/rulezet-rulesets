rule TTP_XOR_WriteProcessMemory_0fcf {
  strings:
    $key_0fcf = { 58 bd [2] 6a 9f [2] 6c aa [2] 42 aa [2] 7d b6 }

  condition:
    any of them
}