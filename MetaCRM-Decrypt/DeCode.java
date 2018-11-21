package shiyu;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.Key;
import java.util.Scanner;

public class DeCode
{
  
  public String enCode(String s)
  {
    return new DES().stringEnc(s, "metacrm");
  }
  
  public String deCode(String s)
  {
    return new DES().stringDec(s, "metacrm");
  }
  
  public static void main(String[] args)
    throws Exception
  {
	DeCode pe = new DeCode();
    while (true) {
    	 BufferedReader strin=new BufferedReader(new InputStreamReader(System.in));  
         System.out.print("请输入一条密文：");  
         String str = strin.readLine();
         String deS = pe.deCode(str);
         System.out.println("明文为："+deS);
	}
  }
}
