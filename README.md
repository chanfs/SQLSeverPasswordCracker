This tool is written by me in 2005 and I submit it to securiteam.com and they changed the name of the tool and post it at http://www.securiteam.com/tools/6Q00I0UEUM.html

------------------------------------------------------------------------

Microsoft SQL Server supports two kinds of authentication:
1) Windows Authentication
2) SQL Server Authentication

SQL Server Authentication is still supported for backward compatibility. SQL Server Authentication is the weaker among the two. In SQL Server Authentication, usernames are sent in the clear, whereas passwords are encrypted using a very simple algorithm. The username and password used for this example is sa/password.

The algorithm to encrypt the password is simply to expand every byte of the password to 2 bytes, swap the higher and lower 4 bits within each byte, xor each byte with A5. For example to encrypt the character "p":

(ASCII is 70 hex):
70 is expanded to 70 00
After the swap the result is: 07 00
XOR with A5: A2 A5

Hence to decrypt it, we will take the odd bytes, XOR with A5, and swap the higher and lower 4 bits.
Take A2
XOR with A5: A2 XOR A5 = 07
Swap: 7 becomes 70.

This tool make use of the WinPcap library and it listen on TCP port 1433 and 2433 and perform the above algorithm to retrieve user name and password.


Chan Fook Sheng