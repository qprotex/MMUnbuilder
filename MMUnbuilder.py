# MMUnbuilder v0.1
# Based in MMBuilder file version 3.00
# Programmed by Miguel Febres
# m.febres at q-protex.com
# http://www.q-protex.com


import sys
import pefile
import zlib
import binascii
import struct
import getopt
import os

def header():
 print u"""\
 
MMUnbuilder - v0.1
Programmed by Miguel Febres - http://www.q-protex.com
"""

def usage():
 header()
 print u"""\
Usage: %s [option]
 
Decompiles mmbuilder exe files.

Options:    
 -u<File>       decompiles given file
 -h             shows this help text
""" % sys.argv[0]

def main(argv):
    
    try:
        opts, args = getopt.gnu_getopt(argv, "u:hl:m:")
    except getopt.GetoptError:
        usage()
        sys.exit(2) 
        
    for o, a in opts:
        if o == "-h":
            usage()
            sys.exit()
        elif o == "-l": #load new mbd to exe
            exeFile=a
        elif o == "-m": #load new mbd to exe
            loadMBD(exeFile,a)  
        elif o == "-u": #unbuild
            if os.path.exists(a):
                unbuild(a)
            else:
                print "File doesn't exist!"
                sys.exit(2)
            
        else:
            usage()
            sys.exit(2)

            
def loadMBD(exeFile,mbdFile):
    header()    
    #Open the exe file
    print "[+] Opening " + exeFile
    pe = pefile.PE(exeFile)
    
    filebuffer = pe.write()
    
    s = pe.sections[-1] #get last section
    eof=s.PointerToRawData + s.SizeOfRawData
    
    #if the size of the file is bigger than last section offset+length 
    print "[+] Checking size..."
    if (len(filebuffer) > eof):
        print "[+] Overlay data found in the end of PE file!"
        #get mmb data
        mmbdata=filebuffer[eof:]
    
        #check header
        sizeHeader=ord(filebuffer[eof])
        print "[+] Checking if overlay data is from Multimedia Builder..."
        if filebuffer[eof+1:eof+sizeHeader-1]=="MMBuilder":
            #print filebuffer[-4:]
            dataSize=struct.unpack("< I", filebuffer[-4:])[0]
            if dataSize>0:
                footerData=filebuffer[eof+dataSize:-4]
                print footerData
                filebuffer=filebuffer[:eof] #discard overlay data
            
                f = open(mbdFile, 'rb')
                mbdContents=f.read()
                sizembdContents=len(mbdContents)
                f.close
                
                f = open(os.path.splitext(exeFile)[0] + ' MODIFIED.exe', 'wb')
                f.write(filebuffer[:eof])
                f.write(mbdContents)
                f.write(footerData)
                f.write(struct.pack("< I",sizembdContents)) #size of footerdata
                f.close
            
        else:
            print "[+] File is not made in MMbuilder!"
  
    else:
        print "[+] File does not have overlay data!" 

    
def unbuild(name):
    header()    
    #Open the exe file
    print "[+] Opening " + name
    pe = pefile.PE(name)
    
    filebuffer = pe.write()
    
    s = pe.sections[-1] #get last section
    eof=s.PointerToRawData + s.SizeOfRawData
    
    #if the size of the file is bigger than last section offset+length 
    print "[+] Checking size..."
    if (len(filebuffer) > eof):
        print "[+] Overlay data found in the end of PE file!"
        #get mmb data
        mmbdata=filebuffer[eof:]
    
        #check header
        sizeHeader=ord(filebuffer[eof])
        print "[+] Checking if overlay data is from Multimedia Builder..."
        if filebuffer[eof+1:eof+sizeHeader-1]=="MMBuilder":
            print "[+] Multimedia Builder format version " + filebuffer[eof+10:eof+sizeHeader+1] + " found!"
            
            print "[+] Checking if data is compiled with security layer..."
            #print ord(filebuffer[eof+sizeHeader+1:eof+sizeHeader+2])
            if ord(filebuffer[eof+sizeHeader+1:eof+sizeHeader+2])==0x01:        
                print "[+] Security Layer FOUND!"
                newPointer = filebuffer[eof+sizeHeader+5:eof+sizeHeader+9]
                sizeProtectedData = struct.unpack("< I", filebuffer[eof+sizeHeader+9:eof+sizeHeader+13])[0] 
                
                print "[+] Size of protected data: " + repr(sizeProtectedData)
                compressedData=filebuffer[eof+sizeHeader+13:eof+sizeHeader+13+sizeProtectedData]
                print "[+] Uncompressing: "             
                mmbdata = zlib.decompress(compressedData)
                
                print "[+] Saving unprotected exe..."
                f = open(os.path.splitext(name)[0] + ' UNPROTECTED.exe', 'wb')
                f.write(filebuffer[:eof]) # save original exe contents
                f.write(mmbdata) #save uncompressed data
                f.write(filebuffer[eof+sizeHeader+13+sizeProtectedData:-4]) #save footer metadata without pointer
                f.write(newPointer)
                f.close
                
            else:
                print "[+] Security Layer not found!"
            
            print "[+] Saving project..."
            f = open(os.path.splitext(name)[0] + '.mbd', 'wb')
            f.write(mmbdata)
            f.close
            
            print "[+] Work done!"
        else:
            print "[+] File is not made in MMbuilder!"        

    else:
            print "[+] File does not have overlay data!"   
            
if __name__ == "__main__":
    if len(sys.argv)>1:
        main(sys.argv[1:])
    else:
        usage()