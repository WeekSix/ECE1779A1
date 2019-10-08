#! python3
import io, sys
from os.path import splitext
from pyrt.math import Vec3
from pyrt.scene import Scene
from pyrt.light import PointLight

from pyrt.renderer import SimpleRT
from PIL import Image
from s3_lib import upload_file_obj
import db_util
import obj_parser

def render(ents):
    """entities is dictionary built in obj_parser.parse() representing objects in scene"""
    #create scene and add objects to scene
    scene=Scene()
    for obj in ents['objects']:
        if isinstance(obj,list):
            for o in obj:
                scene.add(o)
        else:
            scene.add(obj)
    if ents['light'] is None:
        ents['light']=PointLight(Vec3(-1,-8,1))
    scene.addLight(ents['light'])
    scene.setCamera(ents['camera'])
    engine=SimpleRT(shadow=True,iterations=3)
    image=engine.render(scene)
 
    return image


def lambda_handler(event,context):
    """event is a json object"""
    #try:
    ents=obj_parser.parse(event)
    print(ents)
    image = render(ents)
    try:
    	im = Image.fromarray(image.data)
    except AttributeError:
    	im = Image.new("RGB",(image.width,image.height))
    	im.putdata(image.data)
    buf=io.BytesIO()
    _,ext=splitext(ents['id'])
    ext=ext[1:]
    if ext in ('jpg','JPG'):
        ext='jpeg'
    im.save('1.png')#im.save(buf,ext)
    #buf.seek(0)
    #upload_file_obj(buf,ents['id']) #upload to S3

    #set db record status to success
    #db_util.set_request_stat(ents['id'],'success')
#except:
    #set db record status to failed
    #db_util.set_request_stat(ents['id'],'failed')
    #print("something went wrong")