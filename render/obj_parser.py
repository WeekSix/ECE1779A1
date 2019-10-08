import json
from pyrt.geometry import Triangle, Sphere, Vertex
from pyrt.math import Vec3
from pyrt.material import PhongMaterial
from pyrt.camera import PerspectiveCamera
from pyrt.light import PointLight
def parseSphere(entity):
    """process a dictionary (entity) containing 
    info about a sphere and return a pyrt.geometry.Sphere() object
    
    entity=
    {
        "type":"sphere",
        "radius":"string representing a float number",
        "center":"x,y,z",#string of float numbers seperated by commas
        "color":"r,g,b" #int  0-255 seperated by commas,
        "reflectivity":"string representing a float number 0-1"
    }
    """

    if entity['type']!="sphere":
        raise ValueError("entity passed to parseSphere() is not a sphere")
    
    s_center=Vec3(entity['center'].split(','))
    s_color=entity['color'].split(',')
    s_color=Vec3(s_color)
    s_color.normalize()
    if "reflectivity" in entity:
        s_reflect=float(entity['reflectivity'])
        s_material=PhongMaterial(color=s_color,reflectivity=s_reflect)
    else:
        s_material=PhongMaterial(color=s_color)
    s_radius=float(entity['radius'])
    return Sphere(center=s_center,radius=s_radius,material=s_material)

def parseTriangle(entity):
    '''{"type":"triangle","A":"1.2,1.5,3","B":"1.0,6,1","C":'0,0,0','color':'0,1,0'}'''

    if entity['type']!='triangle':
    	raise ValueError("entity passed to parseTriangle is not a triangle")
    A_pos=entity['A'].split(',')
    B_pos=entity['B'].split(',')
    C_pos=entity['C'].split(',')
    assert len(A_pos)==3
    A=Vertex(position=A_pos)
    B=Vertex(position=B_pos)
    C=Vertex(position=C_pos)
    t_color_txt= entity['color'].split(',')
    t_color=Vec3(t_color_txt)
    t_color.normalize()
    if "reflectivity" in entity:
        t_reflect=float(entity['reflectivity'])
        t_material=PhongMaterial(color=t_color,reflectivity=s_reflect)
    else:
        t_material=PhongMaterial(color=t_color)
    return Triangle(A,B,C,material=t_material)


def parseRect(entity):
    '''{"type":"rectangle","A":"1.2,1.5,3","B":"1.0,6,1","C":'0,0,0','color':'0,1,0'}'''

    if entity['type']!='rectangle':
    	raise ValueError("entity passed to parseTriangle is not a rectangle")
    A_pos=entity['A'].split(',')
    B_pos=entity['B'].split(',')
    C_pos=entity['C'].split(',')
    assert len(A_pos)==3
    A=Vertex(position=A_pos)
    B=Vertex(position=B_pos)
    C=Vertex(position=C_pos)
    D=Vertex(position=Vec3(A_pos)+Vec3(C_pos)-Vec3(B_pos))
    print(D.position)
    r_color_txt= entity['color'].split(',')
    r_color=Vec3(r_color_txt)
    r_color.normalize()
    if "reflectivity" in entity:
        r_reflect=float(entity['reflectivity'])
        r_material=PhongMaterial(color=r_color,reflectivity=r_reflect)
    else:
        r_material=PhongMaterial(color=r_color)
    return [Triangle(A,B,C,material=r_material),Triangle(A,C,D,material=r_material)]


def parseLight(entity):
    if entity['type']!='light':
        raise ValueError("entity passed to parseLight is not a light")
    pos=Vec3(entity['position'].split(','))
    return PointLight(pos)
def parseCamera(entity):
    '''{"type":"camera",'position':"0,-10,10",'center':"0,0,0","width":"400","height":"300"}'''
    if entity['type']!='camera':
        raise ValueError("entity passed to parseCamera is not a camera")
    pos=entity['position'].split(',')
    center=entity['center'].split(',')
    c_pos=Vec3(pos)
    c_center=Vec3(center)
    width=int(entity['width'])
    height=int(entity['height'])
    camera=PerspectiveCamera(width,height,45)#default FOV = 45
    camera.setView(c_pos,c_center, Vec3(0.,0.,1.))
    return camera
def parse(request_dic):
        
    id=request_dic['id']
    entities=request_dic['entities']
    objs=[]
    camera=None
    light=None
    for ent in entities:
        if ent['type']=='sphere':
            objs.append(parseSphere(ent))
        elif ent['type'] == 'triangle':
            objs.append(parseTriangle(ent))
        elif ent['type'] == 'rectangle':
            objs += parseRect(ent)
        elif ent['type']=='light':
            light=parseLight(ent)
        elif ent['type']=='camera':
            camera=parseCamera(ent)
    #create default camera
    if camera is None:
        camera = PerspectiveCamera(400, 300, 45)
        camera.setView(Vec3(0.,-10.,10.), Vec3(0.,0.,0.), Vec3(0.,0.,1.))

    ret={'id':id,"objects":objs,'camera':camera,'light':light}
    return ret

if __name__=='__main__':
    d={
        'id':"123.jpg",
        "entities":[
            {"type":"triangle","A":"1.2,1.5,3","B":"1.0,6,1","C":'0,0,0','color':'0,1,0'},
            {"type":"sphere","center":'0,0,0','radius':'1.2','color':'0.4,0.5,0.1',},
            {'position':'1,2,3','type':'light'},
            {"type":"camera",'position':"0,-10,10",'center':"0,0,0","width":"400","height":"300"}
        ]
    }

    ents=parse(d)
    print(ents)