rule DarkComet_Default_Mutex_Memory

{   

     meta:

           Description = "Looks for default DarkComet mutexs"

           filetype = "MemoryDump"              

           Author = "Ian Ahl @TekDefese"

           Date = "12-20-2013"

           reference = "http://www.tekdefense.com/news/2013/12/23/analyzing-darkcomet-in-memory.html"


     strings:

           $s = "DC_MUTEX-" ascii nocase

     condition:

           any of them

}