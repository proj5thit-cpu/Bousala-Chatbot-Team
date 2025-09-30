import mimetypes

def classify_media(filename):
    """
    Classify media type (image, audio, video, other) based on file extension.
    """
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type:
        if mime_type.startswith("image"):
            return "image"
        elif mime_type.startswith("audio"):
            return "audio"
        elif mime_type.startswith("video"):
            return "video"
    return "other"
