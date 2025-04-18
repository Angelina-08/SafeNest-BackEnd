import { Request } from 'express';
import { UploadedFile } from 'express-fileupload';

// Define custom interface to extend Express Request
export interface AuthenticatedRequest extends Request {
  user?: {
    email: string;
    firstName?: string;
    lastName?: string;
  };
  files?: {
    image?: UploadedFile | UploadedFile[];
  };
}
