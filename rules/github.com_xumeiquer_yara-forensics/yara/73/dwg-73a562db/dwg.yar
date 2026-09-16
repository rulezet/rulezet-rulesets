rule dwg: DWG
{
    meta:
        author = "Joan Bono"
        file_info = "AutoDesk AutoCAD Drawing"

    strings:
        $a = {41 43 31 30 31 35} 
        $b = {41 43 31 30 31 38} 
        $c = {41 43 31 30 32 31} 
        $d = {41 43 31 30 32 34} 
        $e = {41 43 31 30 32 37} 
        $f = {4D 43 30 2E 30} 
        $g = {41 43 31 2E 32} 
        $h = {41 43 31 2E 34 30} 
        $i = {41 43 31 30 30 36} 
        $j = {41 43 31 30 30 39} 
        $k = {41 43 31 30 31 30} 
        $l = {41 43 31 30 31 31} 
        $m = {41 43 31 30 31 32} 
        $n = {41 43 31 30 31 33} 

    condition:
       any of them
}