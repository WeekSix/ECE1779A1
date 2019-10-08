import os
import os.path
import boto3
import io
try:
    S3_KEY = os.environ['S3_KEY']
    S3_SECRET = os.environ['S3_SECRET']
    
except KeyError:
    raise EnvironmentError("S3 related environment variables unavailable")
finally:
    S3_BUCKET = 'rtweb-9468'
    S3_ROOT = 'https://s3.us-east-2.amazonaws.com/rtweb-9468'
    s3 = boto3.resource('s3', aws_access_key_id=S3_KEY, aws_secret_access_key=S3_SECRET)
    bucket = s3.Bucket(S3_BUCKET)

def upload_file(path, filename=None):
    """
    upload file to S3_BUCKET, using [string] path, rename the file if filename is not None
    @param path -> path to file
    @param filename -> new name of uploaded file []
    """
    if filename is None:
        filename = os.path.basename(path)
    bucket.upload_file(path, filename)

def upload_file_obj(f_obj, filename):
    """upload a file-like object to S3"""
    bucket.upload_fileobj(f_obj, filename)

def upload_image(image, filename):
    """
    Upload image to S3_BUCKET
    @param image -> an PIL.Image object containing rendered image
    @param filename -> filename to be saved in S3 [includes extension]
    """

    _,ext = os.path.splitext(filename)
    mode = ext[1:] #remove the "." in front
    if mode =='jpg':
        mode = 'jpeg' #Image.save handles jpg file with "jpeg" modoe
    buf = io.BytesIO() 
    image.save(buf, mode)
    buf.seek(0)
    upload_file_obj(buf, filename)
    #by default Bucket.upload_fileobj will close the file-like object when done uploading
