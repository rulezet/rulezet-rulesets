rule TTP_XOR_WriteProcessMemory_ffcf {
  strings:
    $key_ffcf = { a8 bd [2] 9a 9f [2] 9c aa [2] b2 aa [2] 8d b6 }

  condition:
    any of them
}