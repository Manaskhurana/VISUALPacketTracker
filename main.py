import dpkt
import socket
import pygeoip

gi = pygeoip.GeoIP('GeoLiteCity.dat')

def retKML(dstip, srcip):
    try:
        dst = gi.record_by_name(dstip)
        src = gi.record_by_name(srcip)

        if not dst or not src:
            return ''

        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']
        srclongitude = src['longitude']
        srclatitude = src['latitude']

        kml = (
            '<Placemark>\n'
            f'<name>{srcip} to {dstip}</name>\n'
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<LineString>\n'
            '<coordinates>%f,%f %f,%f</coordinates>\n'
            '</LineString>\n'
            '</Placemark>\n'
        ) % (srclongitude, srclatitude, dstlongitude, dstlatitude)

        return kml
    except Exception as e:
        print(f"GeoIP lookup failed for {srcip} or {dstip}: {e}")
        return ''

def plotIPs(pcap):
    kmlPts = ''
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            kmlPts += retKML(dst, src)
        except Exception as e:
            print(f"Packet parse error: {e}")
    return kmlPts

def main():
    with open('wire.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        kmlheader = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<kml xmlns="http://www.opengis.net/kml/2.2">\n'
            '<Document>\n'
            '<Style id="transBluePoly">\n'
            '<LineStyle>\n'
            '<width>1.5</width>\n'
            '<color>501400E6</color>\n'
            '</LineStyle>\n'
            '</Style>\n'
        )
        kmlfooter = '</Document>\n</kml>\n'
        kmldoc = kmlheader + plotIPs(pcap) + kmlfooter
        print(kmldoc)

if __name__ == '__main__':
    main()
